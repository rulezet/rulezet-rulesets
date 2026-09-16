rule TTP_XOR_QUAD_CurrentVersionRun_d9fb {
  strings:
    $key_d9fb = { 8a 94 [2] ae 9a [2] 85 b6 [2] ab 94 [2] bf 8f [2] b0 95 [2] ae 88 [2] ac 89 [2] b7 8f [2] ab 88 [2] b7 a7 }

  condition:
    any of them
}