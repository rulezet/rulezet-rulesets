rule TTP_XOR_QUAD_CurrentVersionRun_def7 {
  strings:
    $key_def7 = { 8d 98 [2] a9 96 [2] 82 ba [2] ac 98 [2] b8 83 [2] b7 99 [2] a9 84 [2] ab 85 [2] b0 83 [2] ac 84 [2] b0 ab }

  condition:
    any of them
}