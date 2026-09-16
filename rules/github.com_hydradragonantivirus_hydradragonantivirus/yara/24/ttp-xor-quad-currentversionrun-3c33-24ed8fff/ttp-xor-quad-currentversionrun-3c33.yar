rule TTP_XOR_QUAD_CurrentVersionRun_3c33 {
  strings:
    $key_3c33 = { 6f 5c [2] 4b 52 [2] 60 7e [2] 4e 5c [2] 5a 47 [2] 55 5d [2] 4b 40 [2] 49 41 [2] 52 47 [2] 4e 40 [2] 52 6f }

  condition:
    any of them
}