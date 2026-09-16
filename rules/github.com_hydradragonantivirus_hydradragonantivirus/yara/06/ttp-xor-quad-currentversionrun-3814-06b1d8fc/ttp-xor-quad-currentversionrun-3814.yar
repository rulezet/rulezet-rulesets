rule TTP_XOR_QUAD_CurrentVersionRun_3814 {
  strings:
    $key_3814 = { 6b 7b [2] 4f 75 [2] 64 59 [2] 4a 7b [2] 5e 60 [2] 51 7a [2] 4f 67 [2] 4d 66 [2] 56 60 [2] 4a 67 [2] 56 48 }

  condition:
    any of them
}