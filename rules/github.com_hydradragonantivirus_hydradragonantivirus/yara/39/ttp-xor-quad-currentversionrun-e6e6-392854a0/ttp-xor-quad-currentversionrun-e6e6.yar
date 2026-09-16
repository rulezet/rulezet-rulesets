rule TTP_XOR_QUAD_CurrentVersionRun_e6e6 {
  strings:
    $key_e6e6 = { b5 89 [2] 91 87 [2] ba ab [2] 94 89 [2] 80 92 [2] 8f 88 [2] 91 95 [2] 93 94 [2] 88 92 [2] 94 95 [2] 88 ba }

  condition:
    any of them
}