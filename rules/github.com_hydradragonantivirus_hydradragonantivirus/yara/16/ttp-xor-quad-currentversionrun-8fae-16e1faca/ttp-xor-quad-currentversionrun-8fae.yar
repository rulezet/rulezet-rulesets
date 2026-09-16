rule TTP_XOR_QUAD_CurrentVersionRun_8fae {
  strings:
    $key_8fae = { dc c1 [2] f8 cf [2] d3 e3 [2] fd c1 [2] e9 da [2] e6 c0 [2] f8 dd [2] fa dc [2] e1 da [2] fd dd [2] e1 f2 }

  condition:
    any of them
}