rule TTP_XOR_QUAD_CurrentVersionRun_eff0 {
  strings:
    $key_eff0 = { bc 9f [2] 98 91 [2] b3 bd [2] 9d 9f [2] 89 84 [2] 86 9e [2] 98 83 [2] 9a 82 [2] 81 84 [2] 9d 83 [2] 81 ac }

  condition:
    any of them
}