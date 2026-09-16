rule XProtect_MULTI_SNOWCAR {
  meta:
    description = "MULTI.SNOWCAR"

  strings:
    $command_test      = { 05 6c 18 00 09 00 1f 00 18 00 4c 00 }
    $command_run       = { 04 ab d9 00 de 00 c5 00 8b 00 }
    $command_port_scan = { 0a 60 10 00 0f 00 12 00 14 00 3f 00 13 00 03 00 01 00 0e 00 40 00 }
    $command_ping_scan = { 0a 75 05 00 1c 00 1b 00 12 00 2a 00 06 00 16 00 14 00 1b 00 55 00 }

  condition:
    2 of them
}