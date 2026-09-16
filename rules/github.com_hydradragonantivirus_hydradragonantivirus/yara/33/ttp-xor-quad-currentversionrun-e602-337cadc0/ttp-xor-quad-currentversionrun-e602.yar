rule TTP_XOR_QUAD_CurrentVersionRun_e602 {
  strings:
    $key_e602 = { b5 6d [2] 91 63 [2] ba 4f [2] 94 6d [2] 80 76 [2] 8f 6c [2] 91 71 [2] 93 70 [2] 88 76 [2] 94 71 [2] 88 5e }

  condition:
    any of them
}