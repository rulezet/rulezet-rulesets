rule paypal_08_14_18_phishing_admin_general {
   meta:
      description = "admin - file general.php"
      author = "Brian Laskowski"
      reference = "https://github.com/Hestat/lw-yara/"
      date = "2018-08-14"
      hash1 = "73897614ef03665e7929e28409dc176e38cd29dda1f7c4c0c5718823b4624d1e"
   strings:
      $s1 = "<input type=\"password\" name=\"apikey\" <?php if($xconfig == true){ echo \"value=\\\"$config_apikey\\\"\"; } ?> required>" fullword ascii
      $s2 = "@eval(file_get_contents($api->dir_config . '/' . $api->general_config));" fullword ascii
      $s3 = "<input type=\"text\" name=\"email\" <?php if($xconfig == true){ echo \"value=\\\"$email_result\\\"\"; } ?> required>" fullword ascii
      $s4 = "<div class=\"left\">Identity Photo<span>allow victim to upload their identity.</span></div>" fullword ascii
      $s5 = "<?php if($xconfig == true && $config_smtp == 1){" fullword ascii
      $s6 = "<form method=\"post\" action=\"\" autocomplete=\"off\">" fullword ascii
      $s7 = "<?php require 'page/header.php'; ?>" fullword ascii
      $s8 = "echo '<option value=\"1\" selected>smtp</option>" fullword ascii
      $s9 = "$a = $_POST['apikey'];" fullword ascii
      $s10 = "if (file_exists($api->dir_config . '/' . $api->general_config))" fullword ascii
      $s11 = "<?php if($xconfig == true && $config_translate == 1){" fullword ascii
      $s12 = "<?php if($xconfig == true && $config_filter == 1){" fullword ascii
      $s13 = "<?php if($xconfig == true && $config_3dsecure == 1){" fullword ascii
      $s14 = "<?php if($xconfig == true && $config_identity == 1){" fullword ascii
      $s15 = "<?php if($xconfig == true && $config_blocker == 1){" fullword ascii
      $s16 = "echo '<option value=\"1\">smtp</option>" fullword ascii
      $s17 = "$b = $_POST['3dsecure'];" fullword ascii
      $s18 = "$f = $_POST['translate'];" fullword ascii
      $s19 = "$photo = $_POST['identity'];" fullword ascii
      $s20 = "if (isset($_GET['success']))" fullword ascii
   condition:
      ( uint16(0) == 0x3f3c and
         filesize < 20KB and
         ( 8 of them )
      ) or ( all of them )
}