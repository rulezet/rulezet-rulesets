rule TTP_XOR_QUAD_CurrentVersionRun_93cc {
  strings:
    $key_93cc = { c0 a3 [2] e4 ad [2] cf 81 [2] e1 a3 [2] f5 b8 [2] fa a2 [2] e4 bf [2] e6 be [2] fd b8 [2] e1 bf [2] fd 90 }

  condition:
    any of them
}