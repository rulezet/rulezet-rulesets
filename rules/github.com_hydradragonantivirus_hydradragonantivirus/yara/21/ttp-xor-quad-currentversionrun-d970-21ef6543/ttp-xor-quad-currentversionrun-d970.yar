rule TTP_XOR_QUAD_CurrentVersionRun_d970 {
  strings:
    $key_d970 = { 8a 1f [2] ae 11 [2] 85 3d [2] ab 1f [2] bf 04 [2] b0 1e [2] ae 03 [2] ac 02 [2] b7 04 [2] ab 03 [2] b7 2c }

  condition:
    any of them
}