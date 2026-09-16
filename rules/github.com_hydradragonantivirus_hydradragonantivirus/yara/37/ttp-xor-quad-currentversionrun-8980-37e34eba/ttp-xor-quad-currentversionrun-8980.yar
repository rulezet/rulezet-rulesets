rule TTP_XOR_QUAD_CurrentVersionRun_8980 {
  strings:
    $key_8980 = { da ef [2] fe e1 [2] d5 cd [2] fb ef [2] ef f4 [2] e0 ee [2] fe f3 [2] fc f2 [2] e7 f4 [2] fb f3 [2] e7 dc }

  condition:
    any of them
}