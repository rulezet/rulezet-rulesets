rule TTP_XOR_QUAD_CurrentVersionRun_6238 {
  strings:
    $key_6238 = { 31 57 [2] 15 59 [2] 3e 75 [2] 10 57 [2] 04 4c [2] 0b 56 [2] 15 4b [2] 17 4a [2] 0c 4c [2] 10 4b [2] 0c 64 }

  condition:
    any of them
}