rule perfcc_script {
    meta:
        author = "tgould@cadosecurity.com"
        description = "Detects script used to set up and retrieve Perfcc"

    strings:
      $env = "AAZHDE"
      $dir = "mkdir /tmp/.perf.c 2>/dev/null"
      $dir_2 = "mkdir /tmp/.xdiag 2>/dev/null"
      $curl = "\"curl/7.74.9\""
      $command = "pkill -9 perfctl &>/dev/null"
      $command_2 = "killall -9 perfctl &>/dev/null"
      $command_3 = "chmod +x /tmp/httpd"

    condition:
        $env and ($dir or $dir_2) and any of ($command*) and $curl

}