rule TTP_XOR_QUAD_CurrentVersionRun_e438 {
  strings:
    $key_e438 = { b7 57 [2] 93 59 [2] b8 75 [2] 96 57 [2] 82 4c [2] 8d 56 [2] 93 4b [2] 91 4a [2] 8a 4c [2] 96 4b [2] 8a 64 }

  condition:
    any of them
}