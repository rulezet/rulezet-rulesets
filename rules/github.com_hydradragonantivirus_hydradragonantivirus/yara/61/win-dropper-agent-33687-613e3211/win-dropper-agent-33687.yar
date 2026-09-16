rule Win_Dropper_Agent_33687
{
strings:
	$a0 = { bf0510400083ec308bece8c8ffffffe8c3ffffff33edbb00144000be????????????????????0055ff542428a3001e400083ee048b0ee30f890d041e40002bf1e805feffffebea50ff542410ff25f8104000ff25fc104000cccc }


condition:
	$a0
}