rule TTP_XOR_QUAD_CurrentVersionRun_073d {
  strings:
    $key_073d = { 54 52 [2] 70 5c [2] 5b 70 [2] 75 52 [2] 61 49 [2] 6e 53 [2] 70 4e [2] 72 4f [2] 69 49 [2] 75 4e [2] 69 61 }

  condition:
    any of them
}