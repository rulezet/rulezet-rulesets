rule TTP_XOR_QUAD_CurrentVersionRun_280d {
  strings:
    $key_280d = { 7b 62 [2] 5f 6c [2] 74 40 [2] 5a 62 [2] 4e 79 [2] 41 63 [2] 5f 7e [2] 5d 7f [2] 46 79 [2] 5a 7e [2] 46 51 }

  condition:
    any of them
}