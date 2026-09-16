rule TTP_XOR_QUAD_CurrentVersionRun_9d70 {
  strings:
    $key_9d70 = { ce 1f [2] ea 11 [2] c1 3d [2] ef 1f [2] fb 04 [2] f4 1e [2] ea 03 [2] e8 02 [2] f3 04 [2] ef 03 [2] f3 2c }

  condition:
    any of them
}