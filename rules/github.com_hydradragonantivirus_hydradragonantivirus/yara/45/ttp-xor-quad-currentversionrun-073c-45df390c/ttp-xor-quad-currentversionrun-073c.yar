rule TTP_XOR_QUAD_CurrentVersionRun_073c {
  strings:
    $key_073c = { 54 53 [2] 70 5d [2] 5b 71 [2] 75 53 [2] 61 48 [2] 6e 52 [2] 70 4f [2] 72 4e [2] 69 48 [2] 75 4f [2] 69 60 }

  condition:
    any of them
}