rule TTP_XOR_QUAD_CurrentVersionRun_de38 {
  strings:
    $key_de38 = { 8d 57 [2] a9 59 [2] 82 75 [2] ac 57 [2] b8 4c [2] b7 56 [2] a9 4b [2] ab 4a [2] b0 4c [2] ac 4b [2] b0 64 }

  condition:
    any of them
}