rule content_injector_layer_4_deobfuscated {
  meta:
    description = "work1 - file content-injector_layer-4-deobfuscated.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "e2228fd80e18aa730f6180c3b70fde47218be6953b1bda1b42d8f8e0b0a7e380"

  strings:
    $s1  = "@setcookie($key, $value_and_ttl[0], time() + $value_and_ttl[0], \"/\", $_SERVER['HTTP_HOST']);" fullword ascii
    $s2  = "if (isset($content[\"options\"][\"type\"]) && $content[\"options\"][\"type\"]==\"inject\")" fullword ascii
    $s3  = "$content = str_replace(\"</head>\", $js_code . \"\\n\" . \"</head>\", $content);" fullword ascii
    $s4  = "foreach ($content[\"headers\"] as $key => $value)" fullword ascii
    $s5  = "$config = 'cTQ9JmsnKnF0KTprLjcoNTAtbihpMHR3Z35xNj4qMmV8cHJtMmFhfkVzaS4gNWYsem1sNShjZyF3PmpkeCotLzgFdixuLyVyJDZsKzZqKnptfiBye" fullword ascii
    $s6  = "$this->config_dict = @unserialize($this->_decrypt(TdsClient::b64d($this->config), \"tmnyrbtvchx5bny\"));" fullword ascii
    $s7  = "foreach (array_merge($_COOKIE, $_POST) as $data_key => $data)" fullword ascii
    $s8  = "foreach ($content[\"cookies\"] as $key => $value_and_ttl)" fullword ascii
    $s9  = "$GLOBALS['injectable_js_code'] = TdsClient::b64d($content[\"data\"]);" fullword ascii
    $s10 = "$context['http']['header'] = 'Content-type: application/x-www-form-urlencoded';" fullword ascii
    $s11 = "if (strpos(strtolower($content), \"</head>\") !== FALSE)" fullword ascii
    $s12 = "private function _http_query_native($url, $content)" fullword ascii
    $s13 = "private function _http_query_curl($url, $content)" fullword ascii
    $s14 = "return @file_get_contents($url, FALSE, $context);" fullword ascii
    $s15 = "public function try_process_check_request()" fullword ascii
    $s16 = "if ($client->try_process_check_request())" fullword ascii
    $s17 = "$query['u'] = @$_SERVER['HTTP_USER_AGENT'];" fullword ascii
    $s18 = "$query['p'] = @$_SERVER['HTTP_HOST'] . @$_SERVER['REQUEST_URI'];" fullword ascii
    $s19 = "public function process_request()" fullword ascii
    $s20 = "$js_code = $GLOBALS['injectable_js_code'];" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 30KB and
      (8 of them)
    ) or (all of them)
}