rule TTP_XOR_QUAD_CurrentVersionRun_eb14 {
  strings:
    $key_eb14 = { b8 7b [2] 9c 75 [2] b7 59 [2] 99 7b [2] 8d 60 [2] 82 7a [2] 9c 67 [2] 9e 66 [2] 85 60 [2] 99 67 [2] 85 48 }

  condition:
    any of them
}