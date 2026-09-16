rule TTP_XOR_QUAD_CurrentVersionRun_de05 {
  strings:
    $key_de05 = { 8d 6a [2] a9 64 [2] 82 48 [2] ac 6a [2] b8 71 [2] b7 6b [2] a9 76 [2] ab 77 [2] b0 71 [2] ac 76 [2] b0 59 }

  condition:
    any of them
}