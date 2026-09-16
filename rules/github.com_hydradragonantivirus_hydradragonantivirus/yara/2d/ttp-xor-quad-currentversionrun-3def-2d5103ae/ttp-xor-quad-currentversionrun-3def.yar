rule TTP_XOR_QUAD_CurrentVersionRun_3def {
  strings:
    $key_3def = { 6e 80 [2] 4a 8e [2] 61 a2 [2] 4f 80 [2] 5b 9b [2] 54 81 [2] 4a 9c [2] 48 9d [2] 53 9b [2] 4f 9c [2] 53 b3 }

  condition:
    any of them
}