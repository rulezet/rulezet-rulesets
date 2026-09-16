rule TTP_XOR_QUAD_CurrentVersionRun_e214 {
  strings:
    $key_e214 = { b1 7b [2] 95 75 [2] be 59 [2] 90 7b [2] 84 60 [2] 8b 7a [2] 95 67 [2] 97 66 [2] 8c 60 [2] 90 67 [2] 8c 48 }

  condition:
    any of them
}