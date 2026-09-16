rule TTP_XOR_QUAD_CurrentVersionRun_70fe {
  strings:
    $key_70fe = { 23 91 [2] 07 9f [2] 2c b3 [2] 02 91 [2] 16 8a [2] 19 90 [2] 07 8d [2] 05 8c [2] 1e 8a [2] 02 8d [2] 1e a2 }

  condition:
    any of them
}