rule TTP_XOR_QUAD_CurrentVersionRun_6ecf {
  strings:
    $key_6ecf = { 3d a0 [2] 19 ae [2] 32 82 [2] 1c a0 [2] 08 bb [2] 07 a1 [2] 19 bc [2] 1b bd [2] 00 bb [2] 1c bc [2] 00 93 }

  condition:
    any of them
}