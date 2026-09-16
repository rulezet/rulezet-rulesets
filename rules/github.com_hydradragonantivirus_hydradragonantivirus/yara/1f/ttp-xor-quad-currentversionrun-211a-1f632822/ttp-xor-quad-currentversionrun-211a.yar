rule TTP_XOR_QUAD_CurrentVersionRun_211a {
  strings:
    $key_211a = { 72 75 [2] 56 7b [2] 7d 57 [2] 53 75 [2] 47 6e [2] 48 74 [2] 56 69 [2] 54 68 [2] 4f 6e [2] 53 69 [2] 4f 46 }

  condition:
    any of them
}