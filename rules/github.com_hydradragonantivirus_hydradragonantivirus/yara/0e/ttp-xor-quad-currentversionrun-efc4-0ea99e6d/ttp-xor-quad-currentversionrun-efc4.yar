rule TTP_XOR_QUAD_CurrentVersionRun_efc4 {
  strings:
    $key_efc4 = { bc ab [2] 98 a5 [2] b3 89 [2] 9d ab [2] 89 b0 [2] 86 aa [2] 98 b7 [2] 9a b6 [2] 81 b0 [2] 9d b7 [2] 81 98 }

  condition:
    any of them
}