rule TTP_XOR_QUAD_CurrentVersionRun_3f13 {
  strings:
    $key_3f13 = { 6c 7c [2] 48 72 [2] 63 5e [2] 4d 7c [2] 59 67 [2] 56 7d [2] 48 60 [2] 4a 61 [2] 51 67 [2] 4d 60 [2] 51 4f }

  condition:
    any of them
}