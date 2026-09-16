rule TTP_XOR_QUAD_CurrentVersionRun_082c {
  strings:
    $key_082c = { 5b 43 [2] 7f 4d [2] 54 61 [2] 7a 43 [2] 6e 58 [2] 61 42 [2] 7f 5f [2] 7d 5e [2] 66 58 [2] 7a 5f [2] 66 70 }

  condition:
    any of them
}