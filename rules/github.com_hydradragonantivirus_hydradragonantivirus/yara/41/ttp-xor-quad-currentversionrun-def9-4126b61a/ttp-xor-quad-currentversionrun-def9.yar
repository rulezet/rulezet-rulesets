rule TTP_XOR_QUAD_CurrentVersionRun_def9 {
  strings:
    $key_def9 = { 8d 96 [2] a9 98 [2] 82 b4 [2] ac 96 [2] b8 8d [2] b7 97 [2] a9 8a [2] ab 8b [2] b0 8d [2] ac 8a [2] b0 a5 }

  condition:
    any of them
}