rule TTP_XOR_QUAD_CurrentVersionRun_0814 {
  strings:
    $key_0814 = { 5b 7b [2] 7f 75 [2] 54 59 [2] 7a 7b [2] 6e 60 [2] 61 7a [2] 7f 67 [2] 7d 66 [2] 66 60 [2] 7a 67 [2] 66 48 }

  condition:
    any of them
}