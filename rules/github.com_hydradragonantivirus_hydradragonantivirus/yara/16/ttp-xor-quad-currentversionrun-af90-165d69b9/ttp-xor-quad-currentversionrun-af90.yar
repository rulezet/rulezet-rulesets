rule TTP_XOR_QUAD_CurrentVersionRun_af90 {
  strings:
    $key_af90 = { fc ff [2] d8 f1 [2] f3 dd [2] dd ff [2] c9 e4 [2] c6 fe [2] d8 e3 [2] da e2 [2] c1 e4 [2] dd e3 [2] c1 cc }

  condition:
    any of them
}