rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4449c8a4cba831a461caf812b1da8224ab1020d8734a39306c3344acb050114"

  strings:
    $s1 = "ter version." fullword wide
    $s2 = "rogram is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHAN" wide
    $s3 = "You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Fo" wide
    $s4 = "This p" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}