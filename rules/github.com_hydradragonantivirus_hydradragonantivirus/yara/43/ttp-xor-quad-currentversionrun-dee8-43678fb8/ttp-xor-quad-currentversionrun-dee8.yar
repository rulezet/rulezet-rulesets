rule TTP_XOR_QUAD_CurrentVersionRun_dee8 {
  strings:
    $key_dee8 = { 8d 87 [2] a9 89 [2] 82 a5 [2] ac 87 [2] b8 9c [2] b7 86 [2] a9 9b [2] ab 9a [2] b0 9c [2] ac 9b [2] b0 b4 }

  condition:
    any of them
}