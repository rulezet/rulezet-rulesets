rule TTP_XOR_QUAD_CurrentVersionRun_eafe {
  strings:
    $key_eafe = { b9 91 [2] 9d 9f [2] b6 b3 [2] 98 91 [2] 8c 8a [2] 83 90 [2] 9d 8d [2] 9f 8c [2] 84 8a [2] 98 8d [2] 84 a2 }

  condition:
    any of them
}