rule TTP_XOR_QUAD_CurrentVersionRun_522f {
  strings:
    $key_522f = { 01 40 [2] 25 4e [2] 0e 62 [2] 20 40 [2] 34 5b [2] 3b 41 [2] 25 5c [2] 27 5d [2] 3c 5b [2] 20 5c [2] 3c 73 }

  condition:
    any of them
}