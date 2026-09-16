rule PEiD_01430_ORiEN_V1_X_V2_X____Fisun_A_V____Sign_by_fly_ {
  meta:
    description = "[ORiEN V1.X-V2.X -> Fisun A.V. ! Sign by fly]"
    ep_only     = "false"

  strings:
    $a = "ORiEN executable files protection system"

  condition:
    $a
}