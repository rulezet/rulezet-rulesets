rule Trojan_Autorun_Win32_Fujacks_PRP_DG {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Fujacks.PRP.DG.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "496a233ebd2a7b2f6a33226111eac5bcd856a827c4aa02df30c51ad27ee55ad4"

  strings:
    $x1  = "Missing %s property(CommandText does not return a result set{Error creating object.  Please verify that the Microsoft Data Acces" wide
    $s2  = "%Operation not allowed in a DBCtrlGrid(Property already defined by lookup field/Grid requested to display more than 256 columns" fullword wide
    $s3  = "ItemIndex out of range0This operation is not supported in provider mode" fullword wide
    $s4  = "\"Failed to set tab \"%s\" at index %d Failed to set object at index %d<MultiLine must be True when TabPosition is tpLeft or tpR" wide
    $s5  = "Could not convert to date%The repository item is not acceptable\"Could not convert to numeric value#Circular referencing is not " wide
    $s6  = "select * from boa order by id" fullword ascii
    $s7  = "select * from Annex" fullword ascii
    $s8  = "#BlobEdit|Represents the BLOB editor;ButtonEdit|Represents an edit control with embedded buttonsECalcEdit|Represents an edit con" wide
    $s9  = "Provider=Microsoft.Jet.OLEDB.4.0; Data Source=" fullword ascii
    $s10 = "Value;ColorComboBox |Represents a editor with color functionality" fullword wide
    $s11 = "Index %d out of bounds" fullword wide
    $s12 = "E%s is not a valid value for field '%s'. The allowed range is %s to %s0'%s' is not a valid integer value for field '%s'0'%s' is " wide
    $s13 = "Invalid value for field '%s'E%g is not a valid value for field '%s'. The allowed range is %g to %g" fullword wide
    $s14 = "is yesterday" fullword wide
    $s15 = "is tomorrow" fullword wide
    $s16 = "is last week" fullword wide
    $s17 = "is last month" fullword wide
    $s18 = "is last year" fullword wide
    $s19 = "is this week" fullword wide
    $s20 = "is this month" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}