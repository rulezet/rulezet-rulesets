rule TTP_XOR_QUAD_CurrentVersionRun_3f03 {
  strings:
    $key_3f03 = { 6c 6c [2] 48 62 [2] 63 4e [2] 4d 6c [2] 59 77 [2] 56 6d [2] 48 70 [2] 4a 71 [2] 51 77 [2] 4d 70 [2] 51 5f }

  condition:
    any of them
}