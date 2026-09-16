rule TTP_XOR_QUAD_CurrentVersionRun_70ee {
  strings:
    $key_70ee = { 23 81 [2] 07 8f [2] 2c a3 [2] 02 81 [2] 16 9a [2] 19 80 [2] 07 9d [2] 05 9c [2] 1e 9a [2] 02 9d [2] 1e b2 }

  condition:
    any of them
}