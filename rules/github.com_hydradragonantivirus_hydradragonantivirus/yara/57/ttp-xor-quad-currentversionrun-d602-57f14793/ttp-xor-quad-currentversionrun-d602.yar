rule TTP_XOR_QUAD_CurrentVersionRun_d602 {
  strings:
    $key_d602 = { 85 6d [2] a1 63 [2] 8a 4f [2] a4 6d [2] b0 76 [2] bf 6c [2] a1 71 [2] a3 70 [2] b8 76 [2] a4 71 [2] b8 5e }

  condition:
    any of them
}