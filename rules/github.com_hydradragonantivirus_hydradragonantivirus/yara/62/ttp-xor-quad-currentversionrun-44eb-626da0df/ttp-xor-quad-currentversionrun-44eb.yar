rule TTP_XOR_QUAD_CurrentVersionRun_44eb {
  strings:
    $key_44eb = { 17 84 [2] 33 8a [2] 18 a6 [2] 36 84 [2] 22 9f [2] 2d 85 [2] 33 98 [2] 31 99 [2] 2a 9f [2] 36 98 [2] 2a b7 }

  condition:
    any of them
}