rule PUP_RMM_AnyDesk_exe {
  meta:
    description   = "Matches AnyDesk remote management tool, often abused for unauthorised access."
    last_modified = "2024-03-03"
    author        = "@petermstewart"
    DaysofYara    = "63/100"
    sha256        = "5beab9f13976d174825f9caeedd64a611e988c69f76e63465ed10c014de4392a"
    sha256        = "7a719cd40db3cf7ed1e4b0d72711d5eca5014c507bba029b372ade8ca3682d70"

  strings:
    $pdb = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb"
    $a1  = "my.anydesk.com"
    $a2  = "AnyDesk Software GmbH" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}