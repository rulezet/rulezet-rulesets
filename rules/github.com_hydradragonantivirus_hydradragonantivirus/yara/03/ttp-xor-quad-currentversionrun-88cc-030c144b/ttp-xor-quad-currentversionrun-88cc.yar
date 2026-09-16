rule TTP_XOR_QUAD_CurrentVersionRun_88cc {
  strings:
    $key_88cc = { db a3 [2] ff ad [2] d4 81 [2] fa a3 [2] ee b8 [2] e1 a2 [2] ff bf [2] fd be [2] e6 b8 [2] fa bf [2] e6 90 }

  condition:
    any of them
}