rule TTP_XOR_QUAD_CurrentVersionRun_287d {
  strings:
    $key_287d = { 7b 12 [2] 5f 1c [2] 74 30 [2] 5a 12 [2] 4e 09 [2] 41 13 [2] 5f 0e [2] 5d 0f [2] 46 09 [2] 5a 0e [2] 46 21 }

  condition:
    any of them
}