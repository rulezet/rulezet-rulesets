rule TTP_XOR_QUAD_CurrentVersionRun_085d {
  strings:
    $key_085d = { 5b 32 [2] 7f 3c [2] 54 10 [2] 7a 32 [2] 6e 29 [2] 61 33 [2] 7f 2e [2] 7d 2f [2] 66 29 [2] 7a 2e [2] 66 01 }

  condition:
    any of them
}