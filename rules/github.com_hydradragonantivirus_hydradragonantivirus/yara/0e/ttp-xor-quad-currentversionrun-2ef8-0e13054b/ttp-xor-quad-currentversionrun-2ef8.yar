rule TTP_XOR_QUAD_CurrentVersionRun_2ef8 {
  strings:
    $key_2ef8 = { 7d 97 [2] 59 99 [2] 72 b5 [2] 5c 97 [2] 48 8c [2] 47 96 [2] 59 8b [2] 5b 8a [2] 40 8c [2] 5c 8b [2] 40 a4 }

  condition:
    any of them
}