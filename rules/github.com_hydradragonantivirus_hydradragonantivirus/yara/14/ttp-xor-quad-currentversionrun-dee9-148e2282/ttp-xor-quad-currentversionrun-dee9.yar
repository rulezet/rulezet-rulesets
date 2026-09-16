rule TTP_XOR_QUAD_CurrentVersionRun_dee9 {
  strings:
    $key_dee9 = { 8d 86 [2] a9 88 [2] 82 a4 [2] ac 86 [2] b8 9d [2] b7 87 [2] a9 9a [2] ab 9b [2] b0 9d [2] ac 9a [2] b0 b5 }

  condition:
    any of them
}