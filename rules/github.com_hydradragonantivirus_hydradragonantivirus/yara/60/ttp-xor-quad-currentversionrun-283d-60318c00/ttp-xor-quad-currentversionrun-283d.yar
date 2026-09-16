rule TTP_XOR_QUAD_CurrentVersionRun_283d {
  strings:
    $key_283d = { 7b 52 [2] 5f 5c [2] 74 70 [2] 5a 52 [2] 4e 49 [2] 41 53 [2] 5f 4e [2] 5d 4f [2] 46 49 [2] 5a 4e [2] 46 61 }

  condition:
    any of them
}